
rule n3e9_1312e39bb6e10b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1312e39bb6e10b12"
     cluster="n3e9.1312e39bb6e10b12"
     cluster_size="346"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downloadguide bundler downloaderguide"
     md5_hashes="['0077ca15e48c55eddbead286417e574c','015c37be1e8884dc29320c6088519aa3','0e346ced3e5b6a05bfe193d9bdba0960']"

   strings:
      $hex_string = { 53756e000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
