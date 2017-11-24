
rule m2321_3b9899a9c8800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.3b9899a9c8800b16"
     cluster="m2321.3b9899a9c8800b16"
     cluster_size="23"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qqpass razy scar"
     md5_hashes="['04fb98d44af05a9e7b0f9cae3881dccc','0518cf1400f8c082d6d08732b9a497b1','ca5c9053e50afdde0489a346ee5006ab']"

   strings:
      $hex_string = { cc8401874a42b1275edb93a8e9c6f7c89cfe00beb79fe8077808e31d510d506c8bd7b6256a5a1346ab39befb588609443461749b79d235150fcf6838361b774b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
