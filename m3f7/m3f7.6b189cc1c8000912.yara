
rule m3f7_6b189cc1c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.6b189cc1c8000912"
     cluster="m3f7.6b189cc1c8000912"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['31beffd9a2f870938f63d2be6dd60c08','967e6712beb48152e587fe30cd97e198','c92bca8396f25da4c3ffb9201421c80f']"

   strings:
      $hex_string = { 643a4458496d6167655472616e73666f726d2e4d6963726f736f66742e416c706861284f7061636974793d3029262333393b3b20206d617267696e2d6c656674 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
