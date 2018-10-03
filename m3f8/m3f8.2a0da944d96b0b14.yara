
rule m3f8_2a0da944d96b0b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f8.2a0da944d96b0b14"
     cluster="m3f8.2a0da944d96b0b14"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="droidkungfu androidos kungfu"
     md5_hashes="['295db17140751496858a1f40210c9b9c8131c66a','fe1f4a4d6aaa56fc9c10df32f9b59f6b9959de66','5289ce037aa8869b630bf4ce9fe1ae974c09075a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m3f8.2a0da944d96b0b14"

   strings:
      $hex_string = { 445f50484f4e455f535441544522202f3e0011436c69636b20466f7220526573746172740010436c69636b20466f7220526573756d65000b436f6e6669672e6a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
