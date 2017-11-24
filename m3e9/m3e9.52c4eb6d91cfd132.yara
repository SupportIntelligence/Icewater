
rule m3e9_52c4eb6d91cfd132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.52c4eb6d91cfd132"
     cluster="m3e9.52c4eb6d91cfd132"
     cluster_size="107"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys jorik"
     md5_hashes="['02a3a76a50edaafd09181ff7f0b5f7fd','097d6b29b32005633f7a38553ea45fd1','56dd90a3c56dc4c418378a1133cc4cd0']"

   strings:
      $hex_string = { 5dfb2f9cfefb278cfeff1b3608001cff0cffccfebcfe1c71146c4cff1be8002a314cff1e7b146c4cff1be9002a314cff1e531504acfc283cff02005dfb331c99 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
