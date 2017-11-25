
rule m3f7_493c5468d9bad111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.493c5468d9bad111"
     cluster="m3f7.493c5468d9bad111"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker cryxos html"
     md5_hashes="['0db389a89503f12baeadf2bf7b3dd7c4','14b251f19d6a22190970fac56eefa022','fb7493abf4738afd71b94a71536cbcd8']"

   strings:
      $hex_string = { 6f63756d656e742e676574456c656d656e7442794964282748544d4c313227292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f57696467 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
