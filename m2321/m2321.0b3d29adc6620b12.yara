
rule m2321_0b3d29adc6620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b3d29adc6620b12"
     cluster="m2321.0b3d29adc6620b12"
     cluster_size="69"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod malob trojandropper"
     md5_hashes="['03a027630c7788a3f94b889f2cd35486','083f99a4c393357489f206e66315e6b8','4b21009b225d2aac68c3c77b392fb932']"

   strings:
      $hex_string = { 4b7f6935b30787ad1746778662125164daed1695e0ecc89ade91dfb41df23cf949de2a33c69934f65b1a2338d29845bd96d44ec4c3cbd88ad1d748a35230ee2b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
