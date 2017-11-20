
rule m3e9_1ada2da0cdbafb16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1ada2da0cdbafb16"
     cluster="m3e9.1ada2da0cdbafb16"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler riskware"
     md5_hashes="['70b020b3f0085d3c2868fbff0b619e4a','94fd0130e724c2556e2dc544623e1acb','bb1b0f3148190b7c54c05d5d429f9a77']"

   strings:
      $hex_string = { 005200650074007200790007002600490067006e006f00720065000400260041006c006c00040042006b00530070000300540061006200030045007300630005 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
