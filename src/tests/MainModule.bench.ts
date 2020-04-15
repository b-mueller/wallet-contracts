import * as ethers from 'ethers'
import { signAndExecuteMetaTx, encodeSalt, multiSignAndExecuteMetaTx } from './utils';

import { MainModule } from 'typings/contracts/MainModule'
import { Factory } from 'typings/contracts/Factory'

ethers.errors.setLogLevel("error")

const FactoryArtifact = artifacts.require('Factory')
const MainModuleArtifact = artifacts.require('MainModule')
const MainModuleDeployerArtifact = artifacts.require('MainModuleDeployer')

const runs = 1000

function report(test: string, values: number[]) {
  const min = Math.min(...values)
  const max = Math.max(...values)
  const avg = values.map((n) => ethers.utils.bigNumberify(n))
    .reduce((p, n) => p.add(n)).div(values.length).toNumber()

  console.info(` -> ${test} runs: ${values.length} cost min: ${min} max: ${max} avg: ${avg}`)
}

contract('MainModule', () => {
  let factory
  let module

  before(async () => {
    // Deploy wallet factory
    factory = await FactoryArtifact.new() as Factory
    // Deploy MainModule
    const tx = await (await MainModuleDeployerArtifact.new()).deploy(factory.address)
    module = await MainModuleArtifact.at(tx.logs[0].args._module) as MainModule
  })

  describe.skip('Benchmark', function () {
    (this as any).timeout(0)

    it('Deploy a wallet', async () => {
      const results: number[] = []

      for (let i = 0; i < runs; i++) {
        const owner = new ethers.Wallet(ethers.utils.randomBytes(32))
        const salt = encodeSalt(1, [{ weight: 1, address: owner.address }])
        const tx = await factory.deploy(module.address, salt)
        results.push(tx.receipt.gasUsed)
      }

      report('deploy wallets', results)
    })

    it('Relay 1/1 transaction', async () => {
      const results: number[] = []

      const transaction = {
        delegateCall: false,
        skipOnError: false,
        target: ethers.constants.AddressZero,
        value: ethers.constants.Zero,
        data: []
      }

      for (let i = 0; i < runs; i++) {
        const owner = new ethers.Wallet(ethers.utils.randomBytes(32))
        const salt = encodeSalt(1, [{ weight: 1, address: owner.address }])
        await factory.deploy(module.address, salt)
        const wallet = await MainModuleArtifact.at(await factory.addressOf(module.address, salt)) as MainModule

        const tx = await signAndExecuteMetaTx(wallet, owner, [transaction]) as any
        results.push(tx.receipt.gasUsed)
      }

      report('relay 1/1 transaction', results)
    })

    it('Relay 2/5 transaction', async () => {
      const results: number[] = []

      const threshold = 4
      const transaction = {
        delegateCall: false,
        skipOnError: false,
        target: ethers.constants.AddressZero,
        value: ethers.constants.Zero,
        data: []
      }

      for (let i = 0; i < runs; i++) {
        const owners = Array(5).fill(new ethers.Wallet(ethers.utils.randomBytes(32)))
        const weights = [3, 3, 1, 1, 1]

        const salt = encodeSalt(
          threshold,
          owners.map((owner, i) => ({
            weight: weights[i],
            address: owner.address
          }))
        )

        await factory.deploy(module.address, salt)
        const wallet = await MainModuleArtifact.at(await factory.addressOf(module.address, salt)) as MainModule

        const signers = [0, 3]

        const accounts = owners.map((owner, i) => ({
          weight: weights[i],
          owner: signers.includes(i) ? owner : owner.address
        }))

        const tx = await multiSignAndExecuteMetaTx(wallet, accounts, threshold, [transaction]) as any
        results.push(tx.receipt.gasUsed)
      }

      report('relay 2/5 transaction', results)
    })
  })
})