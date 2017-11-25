
rule m3e9_6b2f25a5cfa31b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2f25a5cfa31b12"
     cluster="m3e9.6b2f25a5cfa31b12"
     cluster_size="45"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['0218b6c3ffa07a2e4a57493942036d98','08a62b4dacb50f93ab0c8e366526eb04','b32cf6bb2d6130aeb49739723ce2a2e8']"

   strings:
      $hex_string = { cf2ac95a624d932c4f659b0ac0554bc8a4048eaaaf40cb8d52817d7e72dde2aaceba573b845eb915779d269f36c6539c2da987e997b7ecbbaed8f34761db05b0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
