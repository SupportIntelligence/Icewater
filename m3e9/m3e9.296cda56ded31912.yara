
rule m3e9_296cda56ded31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.296cda56ded31912"
     cluster="m3e9.296cda56ded31912"
     cluster_size="46"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus jorik beebone"
     md5_hashes="['155c1722ae95defd35ec6932e148fd75','1a6fd9990cdfa820196428164c2e16bf','b28ec7834a45fa1615e4515f8d66f95b']"

   strings:
      $hex_string = { 14dad9dde1fbfea1067a831b9e8aff9cff9cff07bfe1fa33230000000000000000000000008ef3fbf1f1f1ec6776b30e41b6bcc1d7e2e22c1fe3e3f2eda33410 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
