
rule k3e9_42e2d6d1c8001116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.42e2d6d1c8001116"
     cluster="k3e9.42e2d6d1c8001116"
     cluster_size="59"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob jxol"
     md5_hashes="['057eaa1e9298d2930b961c5e1228f5b4','52b06d885f421f6fc43b96b8cef030ce','b60a12f7f7e4fd2db5b1da9912345a04']"

   strings:
      $hex_string = { eceb26f6c1017417ff45f884c0750838450b88450b7404c6450b018bdaeb0aff45f484c075038955f0423b551472bb33c0403945f87f087537837dfc007e0bc7 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
