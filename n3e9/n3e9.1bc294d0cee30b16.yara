
rule n3e9_1bc294d0cee30b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1bc294d0cee30b16"
     cluster="n3e9.1bc294d0cee30b16"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply graftor malicious"
     md5_hashes="['2f4e2a36fc1b90fadd22acc9c047e4f9','3604c6f1d8f4e15a5ae8ed95d4a3a65d','fcfc729a34739b406090ba9898b4483b']"

   strings:
      $hex_string = { 004d006f006e00030054007500650010002500730020002800250073002c0020006c0069006e00650020002500640029000e0041006200730074007200610063 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
