
rule n3e9_1b225cc348001116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1b225cc348001116"
     cluster="n3e9.1b225cc348001116"
     cluster_size="150"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pykspa vilsel autorun"
     md5_hashes="['00363d6d6b4ef328dc1e8f320a9b9bb1','158663f65f3c1cb2e058291f74479814','65a82f449220c0f923dbf79da6c22153']"

   strings:
      $hex_string = { 3d55b548130c12c29361b63780224b7c110279a603f8a96c69639cce84634a67be28d00efafda25ac997e3fed5f46d31af855f15b4b2507030a3517305a78dec }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
