
rule k2321_292924b49abb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.292924b49abb1932"
     cluster="k2321.292924b49abb1932"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi wbna"
     md5_hashes="['0efababbaa478d651c8dc1db0954988a','14e74e3000cf7800771ad97dee6fac16','e510e676056b4ca1de550640e6fa8d55']"

   strings:
      $hex_string = { f6eb2f3900613e7f21ca74e32a4f932daf83e5e1430bcd194405f21e590a428a16a6299a22341367a89c9bb0cf96fc7c02ee3e9fc65dd71548dea4326c79c59d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
