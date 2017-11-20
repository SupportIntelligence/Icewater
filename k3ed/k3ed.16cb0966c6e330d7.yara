
rule k3ed_16cb0966c6e330d7
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ed.16cb0966c6e330d7"
     cluster="k3ed.16cb0966c6e330d7"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul patched"
     md5_hashes="['17b3d038a9a19e7111a865aca89bd1fc','315bdb03f7f639239679632ac97ef909','61b864a1c9e619117a1c5a4d6d582bed']"

   strings:
      $hex_string = { f8730c8bc78a08880b40433b0672f68b0680380075bec6030033c05f5b5ec9c20400b809000280ebf256bef0576f50ff36ff74240cff151c106f5085c0741283 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
