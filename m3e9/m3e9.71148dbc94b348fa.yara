
rule m3e9_71148dbc94b348fa
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.71148dbc94b348fa"
     cluster="m3e9.71148dbc94b348fa"
     cluster_size="89"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus diple malicious"
     md5_hashes="['0be1d5e0e2e7323bd3196947c0c1ef97','10a73d9ca92354d8b67bd9b2b0695653','937e036d8d42406ab67199c7ba20d9d1']"

   strings:
      $hex_string = { ec205356578965f4c745f8083a40008b75088bc683e0018945fc83e6fe568975088b06ff50048b0633db56895de8895de4ff90b40200003bc3dbe27d1168b402 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
