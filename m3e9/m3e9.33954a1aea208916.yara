
rule m3e9_33954a1aea208916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.33954a1aea208916"
     cluster="m3e9.33954a1aea208916"
     cluster_size="19"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma emotet"
     md5_hashes="['10701363db847b0e6307ea1f3c298ef7','2a9394c42f059f6bcafc8b9a8e662bf3','e1158d6d6522daa6b7aa57078c8f079c']"

   strings:
      $hex_string = { 66071571584432427e57294c794f1b47117c2c230c87226a5a7dca5bdb3e7f350a8ddca6924b7100e3efc175e8b0d323cddfe12fdeb9e248d4a03af0c401a745 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
