
rule n3e9_4b19a16bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4b19a16bc6220b12"
     cluster="n3e9.4b19a16bc6220b12"
     cluster_size="59"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="krypt loadmoney cobra"
     md5_hashes="['0bd813695c5a0653da0c5279bca9a2b8','0ff3db29600232b95ae2c47f04a8f7eb','432e2afc5fd4a47b218faae88cde0764']"

   strings:
      $hex_string = { a91d2e81ff3b7287ee99e146325de67a22dbdcc95975a8a411007d509b1f234326a6b8e77ba52b3a8e797c00000098df5f839f4ec4e3b269b5293f003dcdab30 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
