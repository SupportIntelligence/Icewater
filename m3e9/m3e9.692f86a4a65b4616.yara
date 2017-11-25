
rule m3e9_692f86a4a65b4616
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.692f86a4a65b4616"
     cluster="m3e9.692f86a4a65b4616"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['14409387692d0053bba0afefc614542b','1b7bcb985cdc1e7b1166be69d17d62cc','bdd5c180b32d0f73eda22b89e0700438']"

   strings:
      $hex_string = { fab169e778c7c50c05ec4aca34e864cb4caad7457e5c5a0b3122065008c89ac9003886d4175302193d61beccfdb9098901f9ea1c9f93928a807a353f5ead2343 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
