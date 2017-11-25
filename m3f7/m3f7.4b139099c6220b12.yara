
rule m3f7_4b139099c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.4b139099c6220b12"
     cluster="m3f7.4b139099c6220b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker autolike script"
     md5_hashes="['10cc150e2b845fe8eff820d155e52a5b','2e12cd314a0c861b4723ea5a75a44f0c','dd860353e86e243f4973db2264ce1500']"

   strings:
      $hex_string = { 4143626f2f5038505f53474564687a492f7333362f32312e676966272f3e22293b0a74686554657874203d20746865546578742e7265706c616365282f622d5c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
