
rule n3e9_29c690b9c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29c690b9c6220b12"
     cluster="n3e9.29c690b9c6220b12"
     cluster_size="33"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy cuegoe malicious"
     md5_hashes="['0930f5e4ff0c3d60207c64b6eacad042','12168bb528bd3f8a184b94049e37da9e','a00942485cf0191e7829c0f3a97aef31']"

   strings:
      $hex_string = { 0c8a1c1180f38f8acbf6d132cb80e10f32d98d55ef885def3bd0736a8bca3bf177648bda2bde3bc775478bc82bce83f9fe760a6828664200e8eb6000008bd741 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
