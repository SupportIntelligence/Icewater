
rule m2319_3b1122ceea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b1122ceea210912"
     cluster="m2319.3b1122ceea210912"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['1363dbae12511e421317705efd3b2cd2','1e879714d038616a1f98ded02e9a22fa','970f2c287880f3517f8874be0e365a64']"

   strings:
      $hex_string = { 646f63756d656e742e676574456c656d656e744279496428274e61766261723127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
