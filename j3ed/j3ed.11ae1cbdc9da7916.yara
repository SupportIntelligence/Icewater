
rule j3ed_11ae1cbdc9da7916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3ed.11ae1cbdc9da7916"
     cluster="j3ed.11ae1cbdc9da7916"
     cluster_size="97"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="proxy malicious trojanproxy"
     md5_hashes="['0144b2c8e06be6499873bfc02e28b314','04ca173bf37c20d34956dfb7a132c2d9','2fd437d0ca2c57092abad22704dbe428']"

   strings:
      $hex_string = { d152ba6443b25cb8ce510010408910b26686d6887004b26186d688700851b92a19751787d12910598b15381100102850065aeb05eb62ffd0c35356575bbfa05d }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
