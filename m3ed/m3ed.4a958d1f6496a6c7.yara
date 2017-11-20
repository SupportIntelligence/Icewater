
rule m3ed_4a958d1f6496a6c7
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.4a958d1f6496a6c7"
     cluster="m3ed.4a958d1f6496a6c7"
     cluster_size="34"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['1ae80b34932f757fd034ca61acae4fb2','6e872d3485d13b133010bc8d46444f2e','c709f0d370ab039337ab3639a513a45d']"

   strings:
      $hex_string = { 3acb74060fbec947eb036a30598808404a3bd37fe98b4d143bd388187c12803f357c0deb03c600304880383974f7fe00803e317505ff4104eb158d7e0157e832 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
