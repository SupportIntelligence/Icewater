
rule n3f8_5836954e6a000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.5836954e6a000b12"
     cluster="n3f8.5836954e6a000b12"
     cluster_size="33"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="sandr androidos kasandra"
     md5_hashes="['fe4885d9859104d4ace57c86b0636dde0fbfdc89','132c3027c2eac9eefbbdb809e8d77d047e3f4b35','0ed51ebbba76de239e13b32f7753c6e8bb98e27e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.5836954e6a000b12"

   strings:
      $hex_string = { e30307000a04b1431504b4426e20900048006e10e60307000a047b4482445275a7011506803fc6657f558226c8656e3094004805547485016e30f30834025472 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
