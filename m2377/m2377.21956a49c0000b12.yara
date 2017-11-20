
rule m2377_21956a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.21956a49c0000b12"
     cluster="m2377.21956a49c0000b12"
     cluster_size="11"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['1c6e2801e4a51593f4fa0344579db899','337046f2c85d8dc4c54abf984dcaabb8','f5e0385501b8bb48a04dd64ff8782b0c']"

   strings:
      $hex_string = { 3cdcf705b727455d84946a0d6ce718a0802bdfce111f0edfcd036e4bc39629006bfc239d15534cfad5c76d61a9f3f519263f0412bbd99f9254ea9edd1acca824 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
