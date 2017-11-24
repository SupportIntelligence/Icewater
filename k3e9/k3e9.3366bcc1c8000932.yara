
rule k3e9_3366bcc1c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3366bcc1c8000932"
     cluster="k3e9.3366bcc1c8000932"
     cluster_size="2283"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bublik generickd upatre"
     md5_hashes="['00485919a3abadf7db28c460a5c62205','00bc02e40b80429bb46d3185b08e6206','0332baef0f78fdd9577548b2467d8de5']"

   strings:
      $hex_string = { 5ed2af8aa0e9342f070a04b56e56ceb7f1c8a0070a0446ba5c7d8617a82a020a04487eb4a5cbdceac3080a04e8965df4e0632477010a04809676a9428e9a9b0d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
