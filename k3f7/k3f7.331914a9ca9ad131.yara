
rule k3f7_331914a9ca9ad131
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.331914a9ca9ad131"
     cluster="k3f7.331914a9ca9ad131"
     cluster_size="11"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redir redirector iframe"
     md5_hashes="['0105e8fa0c17ebff157cbed06bfa0fbc','2253382f93623dce9348c66e07a0f768','f9f829b7ec2c2aa2755cdb8f6c9407b2']"

   strings:
      $hex_string = { 5c62272c276727292c6b5b635d297d7d72657475726e20707d28276a2031423d3378284928297b6628712e4f213d315026264d20712e4f213d224c22297b3379 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
