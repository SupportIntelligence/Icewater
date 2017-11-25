
rule m3ed_4a958d1f449696c7
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.4a958d1f449696c7"
     cluster="m3ed.4a958d1f449696c7"
     cluster_size="84"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['00e0f2f823137563982931e27df92959','01ea50f0b548ac519d9a09d04a79a9a5','8f674b00525fea7c569abfe4f8553c51']"

   strings:
      $hex_string = { 3acb74060fbec947eb036a30598808404a3bd37fe98b4d143bd388187c12803f357c0deb03c600304880383974f7fe00803e317505ff4104eb158d7e0157e832 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
