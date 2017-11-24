
rule k2321_09205923d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.09205923d9eb1912"
     cluster="k2321.09205923d9eb1912"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar autorun"
     md5_hashes="['35411852f888076054fd50ce908dd2d2','4c738996640924039c4dee1192429e7f','ffbdbef99edc3e0eeabc30addbc3cb99']"

   strings:
      $hex_string = { e50c5f7417d2271b6cf584de9fe4ec2eb5628906cfc7bf381e6178ea47247d739eeddf8ced5fdc8ffd5af6b650c8f7cc349a533743354dd9c90aa53292058b48 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
