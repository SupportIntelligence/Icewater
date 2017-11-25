
rule n3fd_0842892c5ba30914
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3fd.0842892c5ba30914"
     cluster="n3fd.0842892c5ba30914"
     cluster_size="950"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox yontoo advml"
     md5_hashes="['00043c33a7a31d2449c1a9ff9fa07817','0066d9bdd1495650b1d1e41573720957','045fb0132d53c715356ad499182341b6']"

   strings:
      $hex_string = { 84cd1c0a200101151280ad011300090000151280950113000615128095010e0720020e0e1281e50807021281dd1185050520001185050c07041282791282c408 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
