
rule n3e9_1631512265244a9a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1631512265244a9a"
     cluster="n3e9.1631512265244a9a"
     cluster_size="25"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="softpulse bundler domaiq"
     md5_hashes="['00355db0734d53906c17deeb53af60de','0d824e9cd1214ccdbea3e2d322d7fb9b','b1d9f87cca86688aca99b4f1613e6153']"

   strings:
      $hex_string = { b894d3250406ea294a98794ce377ae2a30f7377ac9a621868745b38a57739697e717a70246fa8d0a392434c10c3220bb856a59cade4874f3a568e9fa2f6f2da2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
