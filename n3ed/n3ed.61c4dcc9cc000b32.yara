
rule n3ed_61c4dcc9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.61c4dcc9cc000b32"
     cluster="n3ed.61c4dcc9cc000b32"
     cluster_size="992"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['011bbf42f7ec4bd8fd7a3741fc84fa0c','020e615e5d4608541eea727ee9f96241','0a8b6653ce2ad9e182d5d966621cb756']"

   strings:
      $hex_string = { 3acb74060fbec947eb036a30598808404a3bd37fe98b4d143bd388187c12803f357c0deb03c600304880383974f7fe00803e317505ff4104eb158d7e0157e832 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
