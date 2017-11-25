
rule n3f7_49140089c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.49140089c6220b12"
     cluster="n3f7.49140089c6220b12"
     cluster_size="15"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['026840cbd2aeaa5c858b4ac455815c3d','0937487c600db30b6e073c07aa230cb0','e1829684a3451dfea2e635d7d9d92404']"

   strings:
      $hex_string = { 6e742e676574456c656d656e74427949642827506f70756c6172506f7374733127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
