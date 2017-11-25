
rule m3ed_4a958d1f449696c5
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.4a958d1f449696c5"
     cluster="m3ed.4a958d1f449696c5"
     cluster_size="120"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['01bb9a9da2da778edd4194d92382a080','053a75754ba606c78ec6c9ab7f2b96c3','3eac06902057875d1e0a333383994978']"

   strings:
      $hex_string = { 3acb74060fbec947eb036a30598808404a3bd37fe98b4d143bd388187c12803f357c0deb03c600304880383974f7fe00803e317505ff4104eb158d7e0157e832 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
