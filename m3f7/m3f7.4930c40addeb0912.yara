
rule m3f7_4930c40addeb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.4930c40addeb0912"
     cluster="m3f7.4930c40addeb0912"
     cluster_size="13"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker script clicker"
     md5_hashes="['0652d1ec449bb41cccb4bec7265b00b4','3ddfe3bc9ca27166181dc225ad431f0d','fe82bc7f199a9825a7add1cf00929301']"

   strings:
      $hex_string = { 63756d656e742e676574456c656d656e744279496428274e61766261723127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f57696467 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
