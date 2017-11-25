
rule m3e9_739728a7c6a6e311
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.739728a7c6a6e311"
     cluster="m3e9.739728a7c6a6e311"
     cluster_size="11006"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy linkury toolbar"
     md5_hashes="['0004df7fd36d38bcb99449f8e819ccd8','0005d2625119407a6f16441c4d5ebfa1','0073f286f9e5ae05b426b036025a674b']"

   strings:
      $hex_string = { 4df051575056e8cb31000083c41085c07405c60300eb558b45f4483945fc0f9cc183f8fc7c2a3bc77d2684c9740a8a064684c075f98846feff75288d45f06a01 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
