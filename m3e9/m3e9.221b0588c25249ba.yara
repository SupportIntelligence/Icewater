
rule m3e9_221b0588c25249ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.221b0588c25249ba"
     cluster="m3e9.221b0588c25249ba"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut midie shodi"
     md5_hashes="['2ca55739e27dc0d263f83872260f29b6','357caea116ca630c386d1f467a7f129c','cc1d7941f17671dd64e45137df1e98db']"

   strings:
      $hex_string = { 99db7b4e83c944f759d67600b5a28574b394dfb16d6e7c37aada4718989dcb43b85d28dc0c0727756fc0ed4af8ad23d405224b6a043021ef8984dee41d7079bd }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
