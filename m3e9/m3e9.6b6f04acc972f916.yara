
rule m3e9_6b6f04acc972f916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b6f04acc972f916"
     cluster="m3e9.6b6f04acc972f916"
     cluster_size="666"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bpchjo"
     md5_hashes="['03dcc8a0542d012a30ad3a9ade7721d2','05245b5f0533ab1466863c0c5d673e2b','297c95621a072ae78c3e3217babef295']"

   strings:
      $hex_string = { 987dd83fbcbefb71628ffdf7428ab4793eb333170f61398ee523fca5ba70e0a0471082da9b2d5b5d9e6d66f08e86243b031bddc81fe9fe4972329a999d78e3f4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
