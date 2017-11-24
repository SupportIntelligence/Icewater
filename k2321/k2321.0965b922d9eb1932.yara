
rule k2321_0965b922d9eb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0965b922d9eb1932"
     cluster="k2321.0965b922d9eb1932"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar autorun"
     md5_hashes="['550ba22b22de759d1de56f59555cbef0','5572676d520ebd51019b777cf9c5bcb6','e68f47a481dd44401f03be84b3f06578']"

   strings:
      $hex_string = { aa4d3e465a18174a67e6a5a6d6a23d29e681ef3b02a460530ff1693cfa14bb1cc34b83a498baf2106dc8e27c1d2bda908d850bf69499f91bb08f162754950c9a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
