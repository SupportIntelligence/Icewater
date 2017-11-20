
rule k3e9_29166d68989b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.29166d68989b0912"
     cluster="k3e9.29166d68989b0912"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['4407893c4be7c1a44feae5613bff8157','44762e208adf5ce729e8b4ee03e28a9b','de19a4ebb4ec785af2e3022c67c1934d']"

   strings:
      $hex_string = { 729d4ca695cb7432b93f6a3664608944c2e588396c5c8c8d089f3261dcb6cd9b8e1c3a6869acbf73f3c6d3870f1eddbb7dffe6f54777efc09a7bb76f99ebea0e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
