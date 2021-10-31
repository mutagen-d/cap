import { EventEmitter } from 'events';

export type LinkType = 'NULL' | 'ETHERNET' | 'IEEE802_11_RADIO' | 'LINKTYPE_LINUX_SLL' | 'RAW'

export type IDevice = {
  name: string;
  description?: string;
  addreses: IAddress[];
  flags?: string
}

export type IAddress = {
  addr: string
  netmask: string
  broadaddr?: string
}

export declare class Cap extends EventEmitter {
  static findDevice(ip?: string): string | undefined
  static deviceList(): IDevice[]
  open(device: string, filter: string, bufSize: number, buffer: Buffer): LinkType;
  send(buffer: Buffer, bufSize: number): void
  close(): void
}

export * as decoders from './Decoders';
