
rule m2321_2b1d908dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2b1d908dc6220b12"
     cluster="m2321.2b1d908dc6220b12"
     cluster_size="21"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod jadtre viking"
     md5_hashes="['037fd24b855230f59d110fa8ace65354','063f34e83fe4f30dd4d8e268c3cf0a7e','c20a4988a7be9269db9b0ca79107264c']"

   strings:
      $hex_string = { ab177a1626e146ba377431a3a289452a124479fd96d909e4d123fa8b00f742a47f580ee6c32463486c78c1fe3f68ec9020e3edade5ccc2e0cf49d5c54db9d003 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
