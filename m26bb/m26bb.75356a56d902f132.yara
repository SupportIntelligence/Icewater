
rule m26bb_75356a56d902f132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.75356a56d902f132"
     cluster="m26bb.75356a56d902f132"
     cluster_size="50"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gandcrab ransom malicious"
     md5_hashes="['2ea3349536497283a49615528d4ed06568c0e04d','db0f3368092a5ef15ea7dc049eda398765e11cc6','64153842f0215605716b9905daf5c80028a0e1a1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.75356a56d902f132"

   strings:
      $hex_string = { 42b640000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
