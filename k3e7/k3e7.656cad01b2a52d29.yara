
rule k3e7_656cad01b2a52d29
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e7.656cad01b2a52d29"
     cluster="k3e7.656cad01b2a52d29"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus chinky diple"
     md5_hashes="['a524133c893b1347d9059ce7859a6c08','b4d53265d699a0e2f413fa88ea65c898','b9be2aaf8f124b85710b2dca45e8b8a5']"

   strings:
      $hex_string = { c9f2f5d9cabfbeb578ae939a8b2d41b6d6f4f5f4f5f4cb4a2e0000001234343051c0cacad9dbf0d935060a0a2f3234404572cad6cabbb575787394978c2d2767 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
