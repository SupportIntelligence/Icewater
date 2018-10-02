
rule m26c1_3398f68dc6220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26c1.3398f68dc6220932"
     cluster="m26c1.3398f68dc6220932"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mirai linux backdoor"
     md5_hashes="['5eb5603c567523c49d1607859572f878808618c8','2bb196bd006febe41e94cd0465084c70ca040f22','fdd11788f192b713ff797864045b5fa1d949119d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26c1.3398f68dc6220932"

   strings:
      $hex_string = { ef847095e50c3007e2040053e3f5ffff0ab040bde81eff2fe1f0412de9c8809fe5a60300eb0c6410e5497e40e208808fe0025086e3060055e12800000a0510a0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
