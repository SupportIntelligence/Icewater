
rule n3f0_199b909dc6620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.199b909dc6620b12"
     cluster="n3f0.199b909dc6620b12"
     cluster_size="20"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="amonetize adae genericr"
     md5_hashes="['09567ebf254d4a89dca15c5e6ea9b905','0e835b7cd62764152e0c3bc24fa4c344','be19cc877c74e3dbd535ba00c7973972']"

   strings:
      $hex_string = { 736697c9a91e7cc20763f8161211ef21c13b4e6204746ecd85b6c3db24babdc48b67a0ea75be6a99383a77d0bbd1a5d7a6b5ccf5ebdd81cf5708e817a2aff3e9 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
