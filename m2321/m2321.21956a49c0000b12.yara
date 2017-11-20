
rule m2321_21956a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.21956a49c0000b12"
     cluster="m2321.21956a49c0000b12"
     cluster_size="26"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['05e45ab265ec2d89ed3a069b310198cc','09807b6d974b09ffbce5222d57d1c68f','87050a519de32a72e51f4ab30555ebab']"

   strings:
      $hex_string = { 50d49675ebce01a9c24989045c078c9a331b9f9bfbe19c1c5784950279c5105315c8b729dca52a2d007383e03528e203e94e210540138d4a6d7ebdea46c90d94 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
