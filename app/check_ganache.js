#!/usr/bin/env node

/**
 * This script establishes a connection to Ganache,
 * verifies the connection, and displays basic information.
 * Run this script to ensure Ganache is properly configured
 * before starting the Flask application.
 */

const Web3 = require('web3');

// Set the Ganache URL
const ganacheUrl = 'http://127.0.0.1:7545';
const web3 = new Web3(ganacheUrl);

async function checkGanacheConnection() {
  console.log('Checking connection to Ganache...');
  
  try {
    // Check if we are connected
    const isConnected = await web3.eth.net.isListening();
    if (!isConnected) {
      throw new Error('Cannot connect to Ganache. Is Ganache running?');
    }
    
    console.log('✅ Connected to Ganache successfully!');
    
    // Get network ID
    const networkId = await web3.eth.net.getId();
    console.log(`Network ID: ${networkId}`);
    
    // Get accounts
    const accounts = await web3.eth.getAccounts();
    console.log(`Available accounts: ${accounts.length}`);
    
    // Display account balances
    console.log('\nAccount Balances:');
    for (let i = 0; i < accounts.length && i < 5; i++) {
      const balance = await web3.eth.getBalance(accounts[i]);
      const etherBalance = web3.utils.fromWei(balance, 'ether');
      console.log(`  Account ${i}: ${accounts[i]}`);
      console.log(`  Balance: ${etherBalance} ETH\n`);
    }
    
    // Get block number
    const blockNumber = await web3.eth.getBlockNumber();
    console.log(`Current block number: ${blockNumber}`);
    
    console.log('\nGanache is properly configured and ready to use with the application!');
    console.log('You can now start the Flask application.');
    
  } catch (error) {
    console.error('❌ Error connecting to Ganache:', error.message);
    console.error('\nPlease ensure that:');
    console.error('1. Ganache is installed and running at ' + ganacheUrl);
    console.error('2. The correct port is configured (default: 7545)');
    console.error('3. There are no firewall issues blocking the connection');
    process.exit(1);
  }
}

checkGanacheConnection();
