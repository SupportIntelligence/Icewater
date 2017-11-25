
rule k3f7_2914a33599ab0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.2914a33599ab0912"
     cluster="k3f7.2914a33599ab0912"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html script"
     md5_hashes="['5779ab16d2be5300a4c82c6500686980','b2eaca6c22cdf434aae052c2913846a0','f05cbbf9e8c3ec094b89277125ddb898']"

   strings:
      $hex_string = { 302f313937312d686f6c64656e2d6774732d6269672d626c6f636b2d70617274792e68746d6c273e3139373120484f4c44454e20475453202d20546865204269 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
