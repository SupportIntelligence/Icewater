
rule k2321_0b1a0cc9cc000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0b1a0cc9cc000912"
     cluster="k2321.0b1a0cc9cc000912"
     cluster_size="19"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['0f75f3a429c177f9077bd945720bc068','188448064405fd0381238c7bc1cd17cb','e6d92da0bb34b72a5d855e72b3037a57']"

   strings:
      $hex_string = { dc1789c3c5df4a1fc94355a7f94bc696e4665f83690e8b63cb729f78076a39aa2764ff3a9b913e7c8ef69e30463d87236676770ffbcd0c6ec7da5198ec745301 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
