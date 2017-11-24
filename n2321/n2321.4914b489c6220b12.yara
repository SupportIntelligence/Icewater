
rule n2321_4914b489c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.4914b489c6220b12"
     cluster="n2321.4914b489c6220b12"
     cluster_size="56"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="snare generickd snarasite"
     md5_hashes="['06a5dfe170ce55550c1321dd32b11e5e','11a18674007119dbdf61670eac50f027','51275dcb21474c207579379780c6cfcc']"

   strings:
      $hex_string = { e4c2e86098c7fdb265d63ff5ba4b06b317f3fbd06681c9e16f35be85c40913d7279a2fd3faec226d12700b2bd4b5586334b9675fead84a578699bdb6ac91f224 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
